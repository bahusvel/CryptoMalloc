## Full command
```sudo python3 pdump.py [PID] | strings | grep -E -o '\b[0-9]{16}\b'```

### Bank app
Needs ```pip3 install simple-crypt```

### Extract RW Memory
```
# sudo is neccessary to access other process pid
sudo python3 pdump.py [pid]
```
### Regex stage

```
#Regex for email:
grep -E -o '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b'
#Regex for credit card number:
grep -E -o '\b[0-9]{16}\b'
```
