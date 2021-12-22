# log4jtool
Find vulnerable versions of Log4j on Linux

This tool does not change anything,  it will iterate through the filesystem looking for Java packages and when it finds  them it will read the manifest looking for vulnerable versions of Log4J and will report the package that contains them.


To run the tool

```
sudo ./log4jtool
```

It doesn't need full root permissions but root will allow it to read anything it could find.
It will search the filesystem for java packages,  .Jar files, .War files and .Ear files.   It will read the contents looking for instances of Log4j and if it finds them it will read the manifest and compare the versions against known vulnerable versions.   It is safe to run and doesn't modify anything.



The output looks like:
```
File: /home/spyderbat/test/log4j/log4j-1.2.12.jar    contains version: 1.2.12  which is not-vulnerable
File: /home/spyderbat/testx/apache-tomcat-8.5.73/webapps/log4shell-demo.war    contains version: 2.14.1  which is vulnerable
```



[Log4jTool X86_64](https://spyderbat.github.io/log4jtool/log4jtool)
[Log4jTool ARM64](https://spyderbat.github.io/log4jtool/log4jtool.arm64)
