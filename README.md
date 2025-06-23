# Kanaya
Simple, unoptimized regular expression engine written for learning purposes. Kanaya takes a regular expression's LR(1) parse tree to an equivalent non-deterministic finite automata, then computes the automata's acceptance of stdin.

## Building
You are sort of out of luck, because this project depends on a personal library I haven't published for little things like a string type and some memory functions. Sorry! You should still be able to use it to see an example of both generating an LR(1) parser from a grammar, and taking a regular expression to nfa. 

## Examples
I still wana show off what it can do though.

```
$ echo xyyyyyyyy | ./bin/kanaya 'x.(y*+z)'
accepted: 1, used: 35432, 34kib
```
```
$ echo 101abcbcba | ./bin/kanaya '(a+b+c)*.(0+1)*.(a+b+c)*'
accepted: 1, used: 92432, 90kib
```
```
$ echo 10101110101abac10 | ./bin/kanaya '(a+b+c)*.(0+1)*.(a+b+c)*'
accepted: 0, used: 94424, 92kib
```
```
$ echo abccba11 | ./bin/kanaya '(a+b+c)*.(0+1)*.(a+b+c)*'
accepted: 1, used: 98456, 96kib
```
