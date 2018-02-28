/**********************************************************************

   File          : cmpsc497-main.c
   Description   : Server project shell

   By            : Trent Jaeger

***********************************************************************/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include "cmpsc497-kvs.h"
#include "cmpsc497-ssl.h"
#include "cmpsc497-format-3.h"   // student-specific

/* Defines */
#define NAME_LEN    16
#define SALT_LEN    16
#define HASH_LEN    32
#define PWD_LEN     (HASH_LEN-SALT_LEN)
#define OBJ_LEN     156 // see what marshall says  // size of object tree for this project
#define KEY_LEN     8
#define PADDING     "----"
#define PAD_LEN     4
#define LINE_SIZE   100

#define PASSWDS_PATH "./passwds-file"
#define OBJECTS_PATH "./objects-file"

struct kvs *Passwds;
struct kvs *Objects;


/* Project APIs */
// public 
extern int set_password( char *username, char *password );
extern int set_object( char *filename, char *username, char *password );
extern int get_object( char *username, char *password, char *id );

// internal
extern int unknown_user( char *username );
extern int authenticate_user( char *username, char *password );
extern struct A *upload_A( FILE *fp , char *filename);
extern struct B *upload_B( FILE *fp );
extern struct C *upload_C( FILE *fp );
extern struct D *upload_D( FILE *fp );
extern struct E *upload_E( FILE *fp );
extern struct F *upload_F( FILE *fp );
extern unsigned char *marshall( struct A *objA );
extern struct A *unmarshall( unsigned char *obj );
extern int output_obj( struct A *objA, char *id );
extern int kvs_dump( struct kvs *kvs, char *filepath );

/*****************************

Invoke:
cmpsc497-p1 set user-name password obj-file
cmpsc497-p1 get user-name password obj-id

Commands:
<set_password> user-name password 
<set_object> user-name password obj-file
<get_object> user-name password obj-id

1 - set password - user name and password
    compute random salt and hash the salt+password

2 - set object - authenticate user for command
    and enter object into object store 

3 - get-object - authenticate user for command
    and retrieve object from object store by id

Object store - array of objects - base object reference and password hash

Need to dump objects and password hashes to file(s)

******************************/

/**********************************************************************

    Function    : main
    Description : Set object or get object in Objects KVS.
                  If password is not already created, an entry
                  is created in the Passwds KVS linking the 
                  username and password for future operations.
    Inputs      : argc - cmpsc497-p1 <op> <username> <password> <file_or_id>
                  argv - <op> may be "set" or "get"
                       - last arg is a filename on "set" (for object input)
                         and an object id on "get" to retrieve object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int main( int argc, char *argv[] )
{
	int rtn;


	//assert( argc == 5 );

	crypto_init();  // Necessary for hashing?
	
	ENGINE *eng = engine_init();

	/* initialize KVS from file */
	Passwds = (struct kvs *)malloc(sizeof(struct kvs));
	Objects = (struct kvs *)malloc(sizeof(struct kvs));
	kvs_init( Passwds, PASSWDS_PATH, NAME_LEN, HASH_LEN, HASH_LEN, PAD_LEN );
	kvs_init( Objects, OBJECTS_PATH, KEY_LEN, OBJ_LEN, NAME_LEN, PAD_LEN );  // OBJ_LEN - size of the object tree for this project

	if ( strncmp( argv[1], "set", 3 ) == 0 ) {
		if ( unknown_user( argv[2] )) {

			rtn = set_password( argv[2], argv[3] );
			assert( rtn == 0 );

		}
		
		rtn = set_object( argv[4], argv[2], argv[3] );
		
	}
	else if ( strncmp( argv[1], "get", 3 ) == 0 ) {
		rtn = get_object( argv[2], argv[3], argv[4] );
	}
	else {
		printf( "Unknown command: %s\nExiting...\n", argv[1] );
		exit(-1);
	}

	kvs_dump( Passwds, PASSWDS_PATH ); 
	kvs_dump( Objects, OBJECTS_PATH ); 

	crypto_cleanup();
	engine_cleanup( eng );
  
	exit(0);
}

/**********************************************************************

    Function    : set_password
    Description : Generate salt and compute password hash
                  Store username (key), password hash (value), and salt (tag) in Passwds KVS
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
//add checks for if malloc, RAND_bytes, digest message
// and kvs auth set return successfully
int set_password( char *username, char *password )
{				
	int passlen;
	char salt[SALT_LEN];

	char *hash; //what we are storing the hash value into
	
	unsigned int hashsize;

	passlen=strlen(password);
	
	unsigned char *str = (unsigned char *)malloc(HASH_LEN);
	char *user=(char *)malloc(NAME_LEN);
	hash = (unsigned char *)malloc(HASH_LEN);
	memset(hash, 0, HASH_LEN);
	memset(str, 0, HASH_LEN);
	memset(user, 0, NAME_LEN);
	memset(salt, 0, SALT_LEN);
	memcpy(user, username, strlen(username));

	RAND_bytes((unsigned char *)salt, SALT_LEN);//create a random buffer
	
	
	memcpy(str, salt, SALT_LEN);
	memcpy(str+strlen(salt), password, passlen);
	//strncat(str, password, passlen);
	//str[HASH_LEN-1] = '\0';
	//creating a hash out of the combo of the salt and the password
	//storing it in hash variable
	digest_message(str, HASH_LEN,  &hash, &hashsize);
	hash[HASH_LEN] = '\0';

	kvs_auth_set(Passwds, user, hash, &salt);
	
	return 0;
}


/**********************************************************************

    Function    : unknown_user
    Description : Check if username corresponds to entry in Passwds KVS
    Inputs      : username - username string from user input
    Outputs     : non-zero if true, NULL (0) if false

***********************************************************************/

int unknown_user( char *username )
{
	unsigned char hash[HASH_LEN];
	unsigned char salt[SALT_LEN];
	unsigned char *name = (unsigned char *)malloc(NAME_LEN);

	assert( strlen( username ) <= NAME_LEN );

	memset( name, 0, NAME_LEN );
	memcpy( name, username, strlen(username) );
	return( kvs_auth_get( Passwds, name, &hash, &salt ));
}


/**********************************************************************

    Function    : authenticate_user
    Description : Lookup username entry in Passwds KVS
                  Compute password hash with input password using stored salt
                  Must be same as stored password hash for user to authenticate
    Inputs      : username - username string from user input
                  password - password string from user input
    Outputs     : non-zero if authenticated, 0 otherwise

***********************************************************************/

int authenticate_user( char *username, char *password )
{
	
	unsigned char *storedHash, *salt, *saltAndPass;
	unsigned char *check;
	//unsigned char check[HASH_LEN];
	int passlen;
	int hashsize;
	
	saltAndPass=(unsigned char *)malloc(HASH_LEN);
	check = (unsigned char *)malloc(HASH_LEN);
	storedHash = (unsigned char *)malloc(HASH_LEN);
	salt = (unsigned char *)malloc(SALT_LEN);
	
	memset(saltAndPass, 0, HASH_LEN);
	memset(salt, 0, SALT_LEN);
	memset(check, 0, HASH_LEN);
	memset(storedHash, 0, HASH_LEN);
	memset(storedHash, 0, HASH_LEN);
	//get password length
	passlen=strlen(password);
	
	//get stored hash in passwds kvs based on username and salt
	kvs_auth_get(Passwds, username, &storedHash, &salt);

	//copy salt & password combo into a char pointer
	memcpy(saltAndPass, salt, SALT_LEN);
	memcpy(saltAndPass+strlen(salt), password, passlen);
	//strncat(saltAndPass, password, passlen);
	
	//create a hash using digest_message
	digest_message(saltAndPass, HASH_LEN,  &check, &hashsize);
	check[HASH_LEN-1] = '\0';
	//printf("%s", check)

	//check if what's returned from digest and storedHash are the same
	if(memcmp(check, storedHash, strlen(check))==0){
		printf("Authentication successful!\n");
		return 1;
	}

	return 0;
}


/**********************************************************************

    Function    : set_object
    Description : Authenticate user with username and password
                  If authenticated, read input from filename file
                  Upload each structure by calling upload_X for struct X
    Inputs      : filename - containing object data to upload
                  username - username string from user input
                  password - password string from user input
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int set_object( char *filename, char *username, char *password )
{
	
	int id, size = LINE_SIZE;
	struct A *objA;
	objA=malloc(OBJ_LEN);
	char *lineone;
	char *token, *token2;
	char *check, line[LINE_SIZE];	
	unsigned char *usnm = malloc(NAME_LEN);
	FILE *fp;
	char s[2] = " ";
	unsigned char *chid = malloc(KEY_LEN);
	lineone = malloc(LINE_SIZE);
	memset(chid, 0, KEY_LEN);
	memset(usnm, 0, NAME_LEN);
	memset(line, 0, LINE_SIZE);
	//memset(check, 0, NAME_LEN);
	memset(lineone, 0, LINE_SIZE);
	memcpy(usnm, username, strlen(username));

	if(authenticate_user(usnm, password)==0){
		printf("Authorization unsuccessful. Exiting now...\n");
		return 1;
	}

	fp=fopen(filename, "r");

	if(fp==NULL){
		printf("File open error. Exiting now...\n");
		return 1;
	}
	
	//fgets(lineone, size, fp);
	getline(&lineone, &size, fp);
	//free(lineone);
	fclose(fp);

	
	token=strtok(lineone, s);

	
	while(token!=NULL){
		check=token;
		token=strtok(NULL,s);
	}
	check[strlen(check)-1]='\0';
	memcpy(chid, check, strlen(check));
	
	
	/*
	//lineone[strlen(lineone)-1]='\0';
	memcpy(line, lineone, strlen(lineone));
	sscanf(line, "%s %s %d", token, token2, &id);
	sprintf(chid, "%d", id);
	puts(chid);
	
	*/

	fp=NULL;
	fp=fopen(filename, "r");
	//check if id int
	objA=upload_A(fp, filename);
	
	//printf("\nOBJECT A%s\n",  objA->num_a);

	if(objA==NULL){
		printf("Set obj fail\n");
		return -1;
	}
	else{
		unsigned char *obj = marshall(objA);
		kvs_auth_set(Objects, chid, obj, usnm);
		//int kvs_auth_set( struct kvs *kvs, unsigned char *key, unsigned char *val, unsigned char *tag )
		return 0;
	}
	fclose(fp);
	
}


/**********************************************************************

    Function    : get_object
    Description : Authenticate user with username and password
                  If authenticated, retrieve object with id from Objects KVS
                  Unmarshall the object into structured data 
                  and output all string and int fields from structs A, B, and last
    Inputs      : username - username string from user input
                  password - password string from user input
                  id - identifier for object to retrieve
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int get_object( char *username, char *password, char *id )
{
	unsigned char *key = (unsigned char *)malloc(KEY_LEN);
	unsigned char *name, *obj;
	char *user=(char *)malloc(NAME_LEN);
	memset(user, 0, NAME_LEN);
	memcpy(user, username, strlen(username));
	int rc;
	

	struct A *objA;

	if ( !authenticate_user( user, password )) {
		fprintf(stderr, "get_object authentication failed %s:%s\n", username, password );
		return -1;
	}

	assert( strlen(id) <= KEY_LEN );  
	assert( strlen(username) <= NAME_LEN );  

	memset( key, 0, KEY_LEN );
	memcpy( key, id, strlen(id) );

	rc = kvs_auth_get( Objects, key, &obj, &name );
	
	if ( rc == 0 ) {  // found object
		// verify name == owner
		if ( strncmp( (char *)name, username, strlen( username )) != 0 ) {
			fprintf(stderr, "get_object failed because user is not owner: %s:%s\n", 
				username, name );
			return -1;
		}

		// output object
		objA = unmarshall( obj );
		output_obj( objA, id );
	}
	else {
		fprintf(stderr, "get_object failed to return object for key: %s\n", id );
		return -1;
	}

	return 0;
}


/**********************************************************************

    Function    : upload_A 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : return objA, NULL if error

***********************************************************************/

struct A *upload_A( FILE *fp , char *filename)
{
	struct A *objA;
	
	objA=malloc(sizeof(struct A));
	int test;
	memset(objA, 0, sizeof(struct A));


	long offset;

	char *sname, *obj_id, *name, *value, *token, *line, lineArr[LINE_SIZE];
	char s[2]=" ";
	int lineone=0, fieldcount = 0, Afields=6, linesize=LINE_SIZE, read;
	line=malloc(LINE_SIZE);
	memset(line, 0, LINE_SIZE);
	memset(lineArr, 0, LINE_SIZE);
	//check fp validity
	if(fp==NULL){
		printf("File pointer error in upload. Exiting now...\n");
		return NULL;
	}
	if(fseek(fp, 0L, SEEK_SET) !=0){
		printf("Seek error.");
		return 1;
	}

	//get the first line in the file
	//fgets(line, LINE_SIZE, fp);
	getline(&line, &linesize, fp);
	
	//fclose(fp);

	int count=0;
	lineone=1;

		do{
			count = count +1;

			
			//get the first token from the line stored in line
			//memset(line, '\0', LINE_SIZE);
			token = strtok(line, s);

			if(strcmp(token, "\n")==0){//blank line skip
				continue;
			}

			//get the struct name
			sname=strtok(NULL,s);
			
			//get the obj ID
			obj_id=strtok(NULL,s);
			



			//fixing crash 1
			//if the first word is not the word field
			//it should definitely be the word struct
			if(strcmp(token, "field")!=0)
			{
				assert(strcmp(token, "struct")==0);
			}
			

			obj_id[(int) strlen(obj_id)-1]='\0';
			//make sure struct name is legit IF token == struct
			if(strcmp(token, "struct")==0)
			{
				if(strcmp(sname, "A") != 0 && strcmp(sname, "B")!= 0 && strcmp(sname, "C")!=0)
				{
					printf("Struct name is not legit. Exiting now...\n");
					return NULL;
				}
				//ensure id is an integer when token == struct
				//assumption: obj id won't be 0
				//fixing crash 2
				assert(atoi(obj_id)!=0);
				assert(strlen(obj_id)==1);
			}

			
			//if the second token is A and the first token is "struct"
			//you can parse the fields
			if(strcmp(sname, "A") == 0 && strcmp(token, "struct")==0){
				//get the next line, should be field
				memset(line, 0, LINE_SIZE);
				while(getline(&line, &linesize, fp)){
					

					token=strtok(line, s);
					name = strtok(NULL, s);
					value = strtok(NULL, s);
					value[strlen(value)-1]='\0';
					assert(strcmp(token, "field")==0);
					assert(strcmp(name, "num_a")==0||strcmp(name, "num_b")==0||strcmp(name, "string_c")==0||strcmp(name, "string_d")==0||strcmp(name, "ptr_e")==0||strcmp(name, "ptr_f")==0);
					if(strcmp(token, "field") ==0){

							
						//in here you need to check that every field name is hit
						//u check number but u also need to chek that its not jst all
						//num_a.. or something like that
						if(strcmp(name, "num_a")==0){
							fieldcount=fieldcount+1;

							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}
							objA->num_a = atoi(value);

						}
						else if(strcmp(name,  "num_b")==0){
							fieldcount=fieldcount+1;

							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}

							objA->num_b = atoi(value);
						}
						else if(strcmp(name,  "string_c")==0){
							fieldcount=fieldcount+1;

							strcpy(objA->string_c, value);
						}
						else if(strcmp(name, "string_d")==0){
							fieldcount=fieldcount+1;
							strcpy(objA->string_d, value);

						}else if(strcmp(name, "ptr_e")==0){
							fieldcount=fieldcount+1;
							offset=ftell(fp);
							objA->ptr_e=upload_B(fp);
							fseek(fp, offset, SEEK_SET);

						}else if(strcmp(name, "ptr_f")==0){
							fieldcount=fieldcount+1;
							offset=ftell(fp);
							objA->ptr_f=upload_C(fp);
							fseek(fp, offset, SEEK_SET);
						}
						else{

							printf("Invalid field name %s. Exiting now...\n", name);
							return NULL;
						}
						
					}

					if (fieldcount==Afields){
						break;
					}
				}
			}

		}while((read=getline(&line, &linesize, fp))!=-1); //if none of the if's hit. i.e. if there isn't an error
		//and if there isn't a "struct A", keep moving through the lines
	//}
	
	
	return objA;
}

/**********************************************************************

    Function    : upload_B 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : return objB, NULL if error

***********************************************************************/

struct B *upload_B( FILE *fp )
{
	struct B *objB;
	
	objB=malloc(sizeof(struct B));
	memset(objB, 0, sizeof(struct B));


	char *sname, *obj_id, *name, *value, *token, *line;
	char s[2]=" ";
	int lineone=0, fieldcount = 0, Bfields=4, linesize=LINE_SIZE, read;
	line=malloc(LINE_SIZE);
	memset(line, 0, LINE_SIZE);
	//check fp validity
	if(fp==NULL){
		printf("File pointer error in upload. Exiting now...\n");
		return NULL;
	}
	if(fseek(fp, 0L, SEEK_SET) !=0){
		printf("Seek error.");
		return 1;
	}
	
	//get the first line in the file
	//fgets(line, LINE_SIZE, fp);
	getline(&line, &linesize, fp);
	lineone=1;
	int count =1;

		do{
			count++;

			//get the first token from the line stored in line
			//memset(line, '\0', LINE_SIZE);
			token = strtok(line, s);

			if(strcmp(token, "\n")==0){//blank line skip
				continue;
			}

			//get the struct name
			sname=strtok(NULL,s);
			
			//get the obj ID
			obj_id=strtok(NULL,s);

			//fixing crash 1
			//if the first word is not the word field
			//it should definitely be the word struct
			if(strcmp(token, "field")!=0)
			{
				assert(strcmp(token, "struct")==0);
			}

			obj_id[strlen(obj_id)-1]='\0';
			//make sure struct name is legit IF token == struct
			if(strcmp(token, "struct")==0){

				if(strcmp(sname, "A") != 0 && strcmp(sname, "B")!= 0 && strcmp(sname, "C")!=0)
				{
					printf("Struct name is not legit. Exiting now...\n");
					return NULL;
				}
				//ensure id is an integer when token == struct
				//assumption: obj id won't be 0
				//fixing crash 2
				
				//assert that obj_id can be converted to an int
				assert(atoi(obj_id)!= 0 && strlen(obj_id) == 1);

			}
			

			
			//if the second token is B and the first token is "struct"
			//you can parse the fields
			if(strncmp(sname, "B", 1) == 0 && strcmp(token, "struct")==0){
				//get the next line, should be field
				memset(line, 0, LINE_SIZE);
				while(getline(&line, &linesize, fp)){
					
					token=strtok(line, s);
					name = strtok(NULL, s);
					value = strtok(NULL, s);

					assert(strcmp(token, "field")==0);
					assert(strcmp(name, "num_b")==0||strcmp(name, "string_a")==0||strcmp(name, "string_c")==0||strcmp(name, "string_d")==0);
					value[strlen(value)-1]='\0';

					if(strcmp(token, "field") ==0){
							
							//in here you need to check that every field name is hit
							//u check number but u also need to chek that its not jst all
							//num_a.. or something like that
						if(strcmp(name, "string_a")==0){
							fieldcount=fieldcount+1;
							strcpy(objB->string_a, value);

						}
						else if(strcmp(name,  "num_b")==0){
							fieldcount=fieldcount+1;
							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}

							objB->num_b = atoi(value);
						}
						else if(strcmp(name,  "string_c")==0){
							fieldcount=fieldcount+1;
							strcpy(objB->string_c, value);
						}
						else if(strcmp(name, "string_d")==0){
							fieldcount=fieldcount+1;
							strcpy(objB->string_d, value);
						}
						else{
							printf("Invalid field name %s. Exiting now...\n", name);
							return NULL;
						}		
					}

					if (fieldcount==Bfields){
						break;
					}
				}
			}
			//printf("\ntoken %s", token);
			//exit(0);
		}while((read=getline(&line, &linesize, fp))!=-1); //if none of the if's hit. i.e. if there isn't an error
		//and if there isn't a "struct A", keep moving through the lines
	//}
	
	
	return objB;
}

/**********************************************************************

    Function    : upload_C 
    Description : For each line in file referenced by fp 
                  Assign value to struct field for object A (ints and strings)
                  or call upload_X function to upload data for struct X
    Inputs      : fp - file pointer for object input file
    Outputs     : return objA, NULL if error

***********************************************************************/

struct C *upload_C( FILE *fp )
{
	struct C *objC;

	objC=malloc(sizeof(struct C));
	memset(objC, 0, sizeof(struct C));

	char *sname, *obj_id, *name, *value, *token, *line;
	char s[2]=" ", line_orig[LINE_SIZE], read, linesize=LINE_SIZE;
	int lineone=0, fieldcount = 0, Cfields=7;
	line=malloc(LINE_SIZE);
	memset(line, 0, LINE_SIZE);
	//check fp validity
	if(fp==NULL){
		printf("File pointer error in upload. Exiting now...\n");
		return NULL;
	}
	if(fseek(fp, 0L, SEEK_SET) !=0){
		printf("Seek error.");
		return 1;
	}
	
	//get the first line in the file
	getline(&line, &linesize, fp);
	lineone=1;

		do{

			//get the first token from the line stored in line
			//memset(line, '\0', LINE_SIZE);
			token = strtok(line, s);

			if(strcmp(token, "\n")==0){//blank line skip
				continue;
			}

			//get the struct name
			sname=strtok(NULL,s);
			
			//get the obj ID
			obj_id=strtok(NULL,s);

			//fixing crash 1
			//if the first word is not the word field
			//it should definitely be the word struct
			if(strcmp(token, "field")!=0)
			{
				assert(strcmp(token, "struct")==0);
			}

			obj_id[strlen(obj_id)-1]='\0';
			//make sure struct name is legit IF token == struct
			if(strcmp(token, "struct")==0){
				if(strcmp(sname, "A") != 0 && strcmp(sname, "B")!= 0 && strcmp(sname, "C")!=0)
				{
					printf("Struct name is not legit. Exiting now...\n");
					return NULL;
				}
				//ensure id is an integer when token == struct
			//assumption: obj id won't be 0
			
				assert(atoi(obj_id)!=0 && strlen(obj_id)==1);
			}

			//if the second token is A and the first token is "struct"
			//you can parse the fields
			if(strcmp(sname, "C") == 0 && strcmp(token, "struct")==0){
				//get the next line, should be field
				memset(line, 0, LINE_SIZE);
				while(getline(&line, &linesize, fp)){
					token=strtok(line, s);
					name = strtok(NULL, s);
					value = strtok(NULL, s);
					assert(strcmp(token, "field")==0);
					assert(strcmp(name, "num_b")==0||strcmp(name, "string_a")==0||strcmp(name, "num_c")==0||strcmp(name, "num_d")==0||strcmp(name, "num_e")==0||strcmp(name, "string_f")==0||strcmp(name, "string_g")==0);
					value[strlen(value)-1]='\0';

						/*

						if(fieldcount != Cfields){
							value[strlen(value)-1]='\0';
						}*/

					if(strcmp(token, "field") ==0){
							
							//in here you need to check that every field name is hit
							//u check number but u also need to chek that its not jst all
							//num_a.. or something like that
							
						if(strcmp(name, "string_a")==0){
							fieldcount=fieldcount+1;

							strcpy(objC->string_a, value);
							
						}
						else if(strcmp(name,  "num_b")==0){
							fieldcount=fieldcount+1;
							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}

							objC->num_b = atoi(value);
						}
						else if(strcmp(name,  "num_c")==0){
							fieldcount=fieldcount+1;
							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}
							objC->num_c = atoi(value);
						}
						else if(strcmp(name,  "num_d")==0){
							fieldcount=fieldcount+1;
							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}

							objC->num_d = atoi(value);
						}
						else if(strcmp(name,  "num_e")==0){
							fieldcount=fieldcount+1;
							if(strcmp(value, "0")!=0){
								assert(atoi(value) != 0);
							}

							objC->num_e = atoi(value);
						}
						else if(strcmp(name,  "string_f")==0){
							fieldcount=fieldcount+1;
							strcpy(objC->string_f, value);
						}
						else if(strcmp(name, "string_g")==0){
							fieldcount=fieldcount+1;
							strcpy(objC->string_g, value);
						}
						else{
							printf("Invalid field name %s. Exiting now...\n", name);
							return NULL;
						}
							
					}
					if(fieldcount==Cfields){
						break;
					}
				}
			}
		}while((read=getline(&line, &linesize, fp))!=-1); //if none of the if's hit. i.e. if there isn't an error
		//and if there isn't a "struct A", keep moving through the lines
	//} 
	return objC;
}


/**********************************************************************

    Function    : marshall
    Description : serialize the object data to store in KVS
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
    Outputs     : unsigned char string of serialized object

***********************************************************************/

unsigned char *marshall( struct A *objA )
{
	unsigned char *obj = (unsigned char *)malloc(OBJ_LEN);
	memset(obj, 0, OBJ_LEN);

	memcpy( obj, &(objA->num_a), sizeof(objA->num_a) );
	printf("\nnumA objA %i\n", objA->num_a);
	memcpy( obj+sizeof(objA->num_a), &(objA->num_b), sizeof(objA->num_b) );
	
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b), &(objA->string_c), sizeof(objA->string_c)); 
	printf("\nstring c objA %s\n", &objA->string_c);

	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)
	+sizeof(objA->string_c), &(objA->string_d), sizeof(objA->string_d));
	printf("\nstring d objA %s\n", &objA->string_d);

	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)
	+sizeof(objA->string_c)+sizeof(objA->string_d), 
	objA->ptr_e, sizeof(struct B) );
	printf("\nstring a objB %s\n", &objA->ptr_e->string_a); 
	
	memcpy( obj+sizeof(objA->num_a)+sizeof(objA->num_b)
	+sizeof(objA->string_c)+sizeof(objA->string_d)
	+sizeof(struct B), objA->ptr_f, sizeof(struct C) ); 
	
	printf("Size of object = %lu\n", 
	       sizeof(objA->num_a)+sizeof(objA->num_b)+sizeof(objA->string_c)
	       +sizeof(objA->string_d)+sizeof(struct B)+sizeof(struct C));
 	
	return obj;
}


/**********************************************************************

    Function    : unmarshall
    Description : convert a serialized object into data structure form
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : obj - unsigned char string of serialized object
    Outputs     : reference to root structure of object

***********************************************************************/

struct A *unmarshall( unsigned char *obj )
{
	struct A *objA = (struct A *)malloc(sizeof(struct A));
	struct B *objB = (struct B *)malloc(sizeof(struct B));
	struct C *objC = (struct C *)malloc(sizeof(struct C));

	memcpy( &(objA->num_a), obj, sizeof(objA->num_a) ); 
	
	memcpy(&(objA->num_b), obj+sizeof(objA->num_a), sizeof(objA->num_b));
	
	memcpy(&(objA->string_c), obj+sizeof(objA->num_a)+sizeof(objA->num_b),
	sizeof(objA->string_c));
	
	memcpy(&(objA->string_d), obj+sizeof(objA->num_a)+sizeof(objA->num_b)
	+sizeof(objA->string_c),sizeof(objA->string_d));
	
	
	memcpy( objB, obj+sizeof(objA->num_a)+sizeof(objA->num_b)
	+sizeof(objA->string_c)+sizeof(objA->string_d), sizeof(struct B) );
	
	memcpy( objC, obj+sizeof(objA->num_a)+sizeof(objA->num_b)
	+sizeof(objA->string_c)+sizeof(objA->string_d)
	+sizeof(struct B), sizeof(struct C) );
	

	objA->ptr_e = objB;
	objA->ptr_f = objC;

	return objA;
}


/**********************************************************************

    Function    : output_obj
    Description : print int and string fields from structs A, B, and last
            *** Below an example is provided for a different object structure ***
            *** Adapt for your object structure ***
    Inputs      : objA - reference to root structure of object
                  id - identifier for the object
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int output_obj( struct A *objA, char *id )
{
	// Base object fields
	printf("ObjA: %s\n", id );
	printf("ObjA -> num_a: %d\n", objA->num_a );
	printf("ObjA -> num_b: %d\n", objA->num_b );
	printf("ObjA -> string_c: %s\n", objA->string_c );
	printf("ObjA -> string_d: %s\n", objA->string_d );

	// First sub-object fields
	printf("ObjB -> string_a: %s\n", objA->ptr_e->string_a );
	printf("ObjB -> num_b: %d\n", objA->ptr_e->num_b );
	printf("ObjB -> string_c: %s\n", objA->ptr_e->string_c );
	printf("ObjB -> string_d: %s\n", objA->ptr_e->string_d );

	// Last sub-object fields
	printf("ObjC -> string_a: %s\n", objA->ptr_f->string_a );
	printf("ObjC -> num_b %d\n", objA->ptr_f->num_b );
	printf("ObjC -> num_c: %d\n", objA->ptr_f->num_c );
	printf("ObjC -> num_d: %d\n", objA->ptr_f->num_d );
	printf("ObjC -> num_e: %d\n", objA->ptr_f->num_e );
	printf("ObjC -> string_f: %s\n", objA->ptr_f->string_f );
	printf("ObjC -> string_g: %s\n", objA->ptr_f->string_g );

	return 0;
}

/**********************************************************************

    Function    : kvs_dump
    Description : dump the KVS to a file specified by path
    Inputs      : kvs - key value store
                  path - file path to dump KVS
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int kvs_dump( struct kvs *kvs, char *path )
{
	int i;
	struct kv_list_entry *kvle;
	struct authval *av;
	struct kvpair *kvp;
	FILE *fp = fopen( path, "w+" ); 

	assert( fp != NULL );

	for (i = 0; i < KVS_BUCKETS; i++) {
		kvle = kvs->store[i];
      
		while ( kvle != NULL ) {
			kvp = kvle->entry;
			av = kvp->av;

			fwrite((const char *)kvp->key, 1, kvs->keysize, fp);
			fwrite((const char *)av->value, 1, kvs->valsize, fp);
			fwrite((const char *)av->tag, 1, kvs->tagsize, fp);
			fwrite((const char *)PADDING, 1, PAD_LEN, fp);
	
			// Next entry
			kvle = kvle->next;
		}
	}
	return 0;
}
