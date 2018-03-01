.PHONY: all oaep time clean

help:
	# all   - build all attacks
	# oaep  - build oaep attack
	# time  - build time attack
	# clean - clean binaries

all: oaep time

oaep:
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/oaep_c.go test/oaep_test.go
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/oaep_c.go pkg/command.go oaep/attack.go

time: time/attack.go
	./build.sh pkg/utils.go pkg/montgomery.go test/mont_test.go
	./build.sh pkg/utils.go pkg/montgomery.go pkg/file.go pkg/time_c.go pkg/command.go time/attack.go

clean:
	rm -f oaep/attack
	rm -f time/attack
	rm -f fault/attack
	rm -f power/attack
	rm -f *.6
