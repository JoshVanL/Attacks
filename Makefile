.PHONY: all oaep time fault clean

help:
	# all   - build all attacks
	# oaep  - build oaep attack
	# time  - build time attack
	# fault - build fault attack
	# clean - clean binaries

all: oaep time fault

build: oaep time fault

oaep:
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/oaep_c.go pkg/command.go oaep/attack.go

time: time/attack.go
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/time_c.go pkg/command.go time/attack.go

fault: fault/attack.go
	./build.sh pkg/utils.go pkg/file.go pkg/command.go fault/attack.go

clean:
	rm -f oaep/attack
	rm -f time/attack
	rm -f fault/attack
	rm -f power/attack
	rm -f *.6
