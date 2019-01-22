#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "jsmn.h"


#define BUFFER_SIZE 5000
#define MAX_TOKEN_COUNT 128
//global variables for saving the data needed from the json files. 
char object[20];
    char name[20];
    char description[20];
    char table[20];
    char port[20];
// Read files
void readfile(char* filepath, char* fileContent)
{
    FILE *f;
    char c;
    int index;
    f = fopen(filepath, "rt");
    while((c = fgetc(f)) != EOF){
        fileContent[index] = c;
        index++;
    }
    fileContent[index] = '\0';
}

// This is where the magic happens
int parseJSON(char *filepath, void callback(char *, char*)){

    char JSON_STRING[BUFFER_SIZE];

    char value[1024];
    char key[1024];

    readfile(filepath, JSON_STRING);

   int i;
   int r;

   jsmn_parser p;
   jsmntok_t t[MAX_TOKEN_COUNT];

   jsmn_init(&p);

   r = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), t, sizeof(t)/(sizeof(t[0])));

   if (r < 0) {
       printf("Failed to parse JSON: %d\n", r);
       return 1;
   }

   /* Assume the top-level element is an object */
   if (r < 1 || t[0].type != JSMN_OBJECT) {
       printf("Object expected\n");
       return 1;
   }

   for (i = 1; i < r; i++){

       jsmntok_t json_value = t[i+1];
       jsmntok_t json_key = t[i];


       int string_length = json_value.end - json_value.start;
       int key_length = json_key.end - json_key.start;

       int idx;

       for (idx = 0; idx < string_length; idx++){
           value[idx] = JSON_STRING[json_value.start + idx ];
       }

       for (idx = 0; idx < key_length; idx++){
           key[idx] = JSON_STRING[json_key.start + idx];
       }

       value[string_length] = '\0';
       key[key_length] = '\0';

       callback(key, value);
       
           
               
       

       i++;
   }

   return 0;
}

// In this function we are saving the information needed for the creation of the lua scripts. 
void mycallback(char *key, char* value){
    //we are testing if the key is matching the desired paramater. 
    int objcompare = strcmp(key,"object");
    int namecompare = strcmp(key,"name");
    int desccompare = strcmp(key,"description");
    int tabcompare = strcmp(key,"table");
    int portcompare = strcmp(key,"port");
           if(objcompare ==0){
                strcpy(object,value);
           }
           else if(namecompare==0){
               
               strcpy(name,value);
           }
           else if(desccompare==0){
               
               strcpy(description,value);
           }
           else if(tabcompare==0){
              
               strcpy(table,value);
           }
           else if(portcompare==0){
               
               strcpy(port,value);
           }
    //debugging for if the statements work. 
    //printf("%s : %s\n", key, name);
   
}
//here is the function for lua script generation.
void makeLua(){
    FILE *ftpr = fopen("output.lua", "w");
    if(!ftpr){
        printf("can't open file\n"); //debug line
    }
    //defining the protype will be done the same in all three dissectors. 
    fprintf(ftpr,"%s = Proto(\"our%s\", \"%s\")\n\n",object, name, description);
    //below is the case for ICMP/v4
    if(strcmp(name,"ICMP")==0){
        fprintf(ftpr, "types =ProtoField.int32(\"%s.types\", \"Type\", base.DEC)\n", object);
        fprintf(ftpr, "code =ProtoField.int32(\"%s.code\", \"Code\", base.DEC)\n", object);
        fprintf(ftpr, "checksum =ProtoField.uint8(\"%s.checksum\", \"Checksum\", base.HEX)\n", object);
        fprintf(ftpr, "ident =ProtoField.int32(\"%s.ident\", \"Identifier\", base.DEC)\n", object);
        fprintf(ftpr, "seqnum =ProtoField.int32(\"%s.seqnum\", \"Sequence Number\", base.DEC)\n", object);
        fprintf(ftpr, "timestamp =ProtoField.absolute_time(\"%s.timestamp\", \"Time Stamp\", base.TIME)\n", object);
        fprintf(ftpr, "%s.fields = {types, code, checksum, ident, seqnum, timestamp}\n\n", object);
        fprintf(ftpr, "function %s.dissector(buffer, pinfo, tree)\n", object);
        fprintf(ftpr, " length = buffer:len()\n\n");
        fprintf(ftpr, " if length ==0 then return end\n");
        
        fprintf(ftpr, "pinfo.cols.protocol = %s.name\n", object);
        
        fprintf(ftpr, "local subtree = tree:add(%s, buffer(), \"%s data \")\n\n", object, description);
        
        fprintf(ftpr, "subtree:add_le(types, buffer(0,1))\n");
        fprintf(ftpr, "subtree:add_le(code, buffer(1,1))\n");
        fprintf(ftpr, "subtree:add(checksum, buffer(2,2))\n");
        fprintf(ftpr, "subtree:add(ident, buffer(4,2))\n");
        fprintf(ftpr, "subtree:add(seqnum, buffer(6,2))\n");
        fprintf(ftpr, "subtree:add(timestamp, buffer(8,8))\n");
        
        
    }
    //the RIP case
    if(strcmp(name,"RIP")==0){
        fprintf(ftpr, "version =ProtoField.int32(\"%s.version\", \"Version\", base.DEC)\n", object);
        fprintf(ftpr, "command =ProtoField.int32(\"%s.command\", \"Command\", base.DEC)\n", object);
        fprintf(ftpr, "%s.fields = {version, command}\n\n", object);
        fprintf(ftpr, "function %s.dissector(buffer, pinfo, tree)\n", object);
        fprintf(ftpr, " length = buffer:len()\n\n");
        fprintf(ftpr, " if length ==0 then return end\n");
        
        fprintf(ftpr, "pinfo.cols.protocol = %s.name\n", object);
        
        fprintf(ftpr, "local subtree = tree:add(%s, buffer(), \"%s data \")\n\n", object, description);
        fprintf(ftpr, "subtree:add_le(version, buffer(1,1))\n");
        fprintf(ftpr, "subtree:add(command, buffer(0,1))\n");
    }
    //lastly the RTP case
    if(strcmp(name,"RTP")==0){
        fprintf(ftpr, "rtpversion =ProtoField.int32(\"%s.rtpversion\", \"Version\", base.DEC)\n", object);
        fprintf(ftpr, "rtppadding =ProtoField.string(\"%s.rtppadding\", \"Padding\")\n", object);
        fprintf(ftpr, "rtpmark =ProtoField.string(\"%s.rtpmark\", \"Marking\")\n", object);
        fprintf(ftpr, "rtpsequence =ProtoField.int32(\"%s.rtpsequence\", \"Sequence\", base.DEC)\n", object);
       fprintf(ftpr, "rtppayload =ProtoField.int32(\"%s.rtppayload\", \"Payload\", base.DEC)\n", object); 
        fprintf(ftpr, "%s.fields = {rtpversion, rtppadding, rtpmark, rtpsequence, rtppayload}\n\n", object);
        fprintf(ftpr, "function %s.dissector(buffer, pinfo, tree)\n", object);
        fprintf(ftpr, " length = buffer:len()\n\n");
        fprintf(ftpr, " if length ==0 then return end\n");
        
        fprintf(ftpr, "pinfo.cols.protocol = %s.name\n", object);
        
        fprintf(ftpr, "local subtree = tree:add(%s, buffer(), \"%s data \")\n\n", object, description);
        fprintf(ftpr, "local version = buffer(0,1):bitfield(0,2)\n");
        fprintf(ftpr, "local padding = buffer(0,1):bitfield(2,3)\n");
        fprintf(ftpr, "local mark = buffer(1,1):bitfield(0,1)\n");
        fprintf(ftpr, "local marking = \"false\"\n");
        fprintf(ftpr, "if mark==1 then marking = \"true\" end\n");
        fprintf(ftpr, "local pad = \"false\"\n");
        fprintf(ftpr, "     if padding==1 then pad = \"true\" end\n");
        fprintf(ftpr, "local sequence = buffer(2,2):bitfield(0,16)\n");
        fprintf(ftpr, "local payload = buffer(1,1):bitfield(1,7)\n");
        fprintf(ftpr, "local subtree = tree:add(%s, buffer(), \"%s data \")\n\n", object, description);
        
        fprintf(ftpr, "subtree:add_le(rtpversion, version)\n");
        fprintf(ftpr, "subtree:add(rtppadding, pad)\n");
        fprintf(ftpr, "subtree:add(rtpmark, mark)\n");
        fprintf(ftpr, "subtree:add(rtpsequence, sequence)\n");
        fprintf(ftpr, "subtree:add(rtppayload, payload)\n");
    }
    //these last lines are always needed, we just call our global variables.
    fprintf(ftpr,"end\n");
    fprintf(ftpr, "porttable = DissectorTable.get(\"%s\")\n", table);
    fprintf(ftpr, "porttable:add(%s, %s)\n", port, object);
    if(strcmp(name,"RTP")==0){
        fprintf(ftpr, "porttable:add(5060, %s)\n", object);
    }
}
int main()
{
    //prompting the user for json files. 
    char JSON_FILE_PATH[10];
    printf("Enter JSON file name\n");
    scanf("%s", &JSON_FILE_PATH);
    
    parseJSON(JSON_FILE_PATH, mycallback); //parse through json and pull out needed info
    makeLua(); //generate lua 
    return 0;
}
