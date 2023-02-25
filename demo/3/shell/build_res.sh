rm ./statik/*.go
./shell/statik -include=*.jpg,*.txt,*.html,*.css,*.js,*.conf,*.ini,*.*,* -src=./resource 

sudo chown zengfr:root -R ./
sudo chmod 777 -R ./
cd ..