.PHONY: all oaep time fault power clean

help:
	# all   - build all attacks
	# oaep  - build oaep attack
	# time  - build time attack
	# fault - build fault attack
	# power - build power attack
	# clean - clean binaries

all: oaep time fault power

build: oaep time fault power

oaep:
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/oaep_c.go pkg/command.go oaep/attack.go

time: time/attack.go
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/time_c.go pkg/command.go time/attack.go

fault: fault/attack.go
	./build.sh pkg/utils.go pkg/file.go pkg/fault_c.go pkg/command.go fault/attack.go

power: power/attack.go
	./build.sh pkg/utils.go pkg/file.go pkg/command.go power/attack.go

clean:
	rm -f oaep/attack
	rm -f time/attack
	rm -f fault/attack
	rm -f power/attack
	rm -f *.6
