pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./validate_password.circom";

template Register(n, s, minLength) {
    signal input password[n];
    signal output computedHash; // hash (password)
    // validate password
    component validator = validatePassword(n, minLength);
    for (var i = 0; i < n; i++){
        validator.password[i] <== password[i];
    }
    // chuyển pass 128 bytes thành mảng 8 phần tử
    var size = n\s;
    signal combine[size];
    for (var i = 0; i < n; i += s){
        var val = 0;
        for(var j = 0; j < s; j++){
            val += password[i+j] * (256 ** j);
        }
        combine[i\s] <-- val;
    }
    // tạo hash Poseidon của password
    component hasher = Poseidon(size);
    for(var i = 0; i < size; i++){
        hasher.inputs[i] <== combine[i];
    }
    // ràng buộc đầu ra
    computedHash <== hasher.out;
}

component main = Register(128, 16, 8);