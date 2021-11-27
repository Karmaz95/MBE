# Program is asking for 2 files to read and compare:
'''
Usage: ./lab8C {-fn=<filename>|-fd=<file_descriptor>} {-fn=<filename>|-fd=<file_descriptor>}
'''

# I can sepcify a filename or it's descriptor which is an integer.
# There are always 3 standard descriptors and if the file is cloned / forked / open there are 'n' descriptor.
'''
0 - stdin
1 - stdout
2 - stderr
n - which indicates the file cloned / forked / opened:
'''

# In this lab I could specify 2 files to compare like below:
'''
❯ ./lab8C -fn=.pass -fn=.pass
"<<<For security reasons, your filename has been blocked>>>" is lexicographically equivalent to "<<<For security reasons, your filename has been blocked>>>"
'''
# As it is shown above, there is blockade which not print the file content if it has .pass in the name, but it can be easilly bypassed by descriptor:
'''
❯ ./lab8C -fn=.pass -fd=3
"<<<For security reasons, your filename has been blocked>>>" is lexicographically equivalent to "3v3ryth1ng_Is_@_F1l3
'''