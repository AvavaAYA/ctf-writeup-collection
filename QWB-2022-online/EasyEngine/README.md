Compile
```bash
git clone https://github.com/nginx/njs.git
git reset --hard 404553896792b8f5f429dc8852d15784a59d8d3e
git apply < 1.diff
./configure --cc-opt="-g0 -O2 -D_FORTIFY_SOURCE=2 -fcf-protection -fstack-protector-all" --ld-opt="-Wl,-S,-O1,-z,relro,-z,now" --test262=NO --debug=YES && make -j
```bash
