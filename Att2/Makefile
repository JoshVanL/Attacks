.PHONY: all fault power clean

help:
	# all   - build all attacks
	# fault - build fault attack
	# power - build power attack
	# clean - clean binaries

all: fault power

build: fault power

fault: fault/attack.go
	./build.sh pkg/utils.go pkg/file.go pkg/fault_c.go pkg/command.go fault/attack.go

power: power/attack.go
	./build.sh pkg/utils.go pkg/file.go pkg/command.go pkg/power_c.go power/attack.go

clean:
	rm -f oaep/attack
	rm -f time/attack
	rm -f fault/attack
	rm -f power/attack
	rm -f *.6
