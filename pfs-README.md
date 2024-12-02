`test_open.c` is found in `examples/open_interceptor`


```bash
gcc -o test_open test_open.c
```

```bash
env LD_LIBRARY_PATH=/home/jaytau/Programming/syscall_intercept/build LD_PRELOAD=../../build/examples/libfile_open_interceptor.so ./test_open
```