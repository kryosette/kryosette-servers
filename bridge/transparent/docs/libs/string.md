/*
    The strlen() function calculates the length of the string pointed
       to by s, (!) excluding the terminating null byte ('\0') (!)

    The  strlen()  function	computes  the  length  of  the	string s.  The
       strnlen() function attempts to compute the length of s, but never scans
       beyond the first	maxlen bytes of	s.
    
    Problem: If the string does not end with '\0', the function will read the memory until it finds a random zero byte (or a segfault occurs).
    */
size_t len = strlen(ip_address);