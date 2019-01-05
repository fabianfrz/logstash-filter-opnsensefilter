Logstash filter to parse the firewall log of OPNsense
=====================================================

Example:


```
input {
  stdin {
  }
}
filter {
    opnsensefilter {}
}

output {
    stdout { }
}
```

