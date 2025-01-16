pragma circom 2.0.0;
include "./node_modules/circomlib/circuits/poseidon.circom";
include "./validate_password.circom"
template ChangePassword(n, s, minLength) {
    signal input oldPassword[n];
    signal input newPassword[n];
    signal output computedHashOldPass;
    signal output computedHashNewPass;
    // validate old password
    component validatorOldPass = validatePassword(n, minLength);
    for (var i = 0; i < n; i++){
        validatorOldPass.password[i] <== oldPassword[i];
    }
    // validate new password
    component validatorNewPass = validatePassword(n, minLength);
    for (var i = 0; i < n; i++){
        validatorNewPass.password[i] <== newPassword[i];
    }
    // Mật khẩu mới khác mật khẩu cũ
    var matchCount = 0;
    for (var i = 0; i < n; i++){
        if(oldPassword[i] == newPassword[i]){
            matchCount += 1;
        }
    }
    assert(matchCount < n);
    // chuyển đầu vào 128 bytes thành mảng 8 phần tử
    var size = n\s;
    signal combineOldPassword[size];
    signal combineNewPassword[size];
    for (var i = 0; i < n; i += s){
        var val = 0;
        var valNew = 0;
        for(var j = 0; j < s; j++){
            val += oldPassword[i+j] * (256 ** j);
            valNew += newPassword[i+j] * (256 ** j);
        }
        combineOldPassword[i\s] <-- val;
        combineNewPassword[i\s] <-- valNew;
    }
    // tạo hash Poseidon của mật khẩu cũ
    component hasherOldPass = Poseidon(size);
    for(var i = 0; i < size; i++){
        hasherOldPass.inputs[i] <== combineOldPassword[i];
    }
    // tạo hash Poseidon của mật khẩu mới
    component hasherNewPass = Poseidon(size);
    for(var i = 0; i < size; i++){
        hasherNewPass.inputs[i] <== combineNewPassword[i];
    }
    // ràng buộc đầu ra
    computedHashOldPass <== hasherOldPass.out;
    computedHashNewPass <== hasherNewPass.out;
}
component main = ChangePassword(128, 16, 8);