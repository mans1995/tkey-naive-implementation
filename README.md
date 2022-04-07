# tkey-naive-implementation

## Installation
```
make
```

Existing parameter file:
- **.k** (hash chain length)

## Usage

### Setup
```
./tkey 0
```
Creates the following parameter files:
- **.pk** (initial secret key)
- **.salt** (salt)
- **.tinit** (initial time)
- **.tprev** (time of last successful verification)
- **.pprev** (password of last successful verification)
#### Setup time testing
Running the following command will run 50 setups and outputs the average time used to setup.
```
./tkey time_setup
```


### Password generation
```
./tkey 1
```
Creates the following parameter file:
- **.pi** (password generated by the prover)

#### Password generation time testing
Running the following command will run 50 password generations and outputs the average time used to generate a password.
```
./tkey time_gen
```

### Password verification
```
./tkey 2
```
#### Password verification time testing
Running the following command will run 50 password verifications and outputs the average time used to verify a password.
```
./tkey time_check
```

## Visualization

```
make show
```
Time parameters are divided/rounded to the lowest multiple of 30. Password parameters are base32 encoded.

## Uninstallation
```
make clean
```
