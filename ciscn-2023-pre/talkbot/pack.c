//serialize_main.c
#include <stdio.h>
#include <stdlib.h>
#include "devicemsg.pb-c.h"

int main (int argc, const char * argv[]) 
{
  Devicemsg msg = DEVICEMSG__INIT; // AMessage
  void *buf;                     // Buffer to store serialized data
  unsigned len;                  // Length of serialized da
    FILE* fd = fopen("./tmpdata", "rb");
    char databuf[0x500];
    fgets(databuf, 0x500, fd);

  msg.actionid  = atoi(argv[1]);
  msg.msgidx    = atoi(argv[2]);
  msg.msgsize   = atoi(argv[3]);
  msg.msgcontent= databuf;
  len = devicemsg__get_packed_size(&msg);

  buf = malloc(len);
  devicemsg__pack(&msg,buf);

  fprintf(stderr,"Writing %d serialized bytes\n",len); // See the length of message
  fwrite(buf,len,1,stdout); // Write to stdout to allow direct command line piping

  free(buf); // Free the allocated serialized buffer
  return 0;
}
