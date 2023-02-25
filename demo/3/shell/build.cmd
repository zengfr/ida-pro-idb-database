
#
cls
go env
ldd  --version
gcc  --version
go build
go build -ldflags='-s -w'
go build -ldflags='-s -w -linkmode "external" -extldflags "-static"' -o ./demo.exe 

#go build -gcflags="-N -l=4"  -ldflags=" -extldflags='-static'" -a -x -work >build.log
#go build -gcflags="-N -l=4"  -ldflags="-s -w -extldflags='-static'" -o ./demo.exe

#pause

--ldflags '--extldflags "-static -fpic"'