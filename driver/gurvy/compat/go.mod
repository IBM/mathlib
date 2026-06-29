module github.com/IBM/mathlib/driver/gurvy/compat

go 1.26.3

replace github.com/IBM/mathlib => ../../..

require (
	github.com/IBM/mathlib v0.0.0-00010101000000-000000000000
	github.com/consensys/gnark-crypto v0.20.1
	github.com/kilic/bls12-381 v0.1.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
