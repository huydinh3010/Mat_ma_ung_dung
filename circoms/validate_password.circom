pragma circom 2.0.0;
template validatePassword(n, minLength){
    signal input password[n];
    var countZero = 0;
    var specialCharCount = 0;
    var isPadding = 1;
    for (var i = n - 1; i >= 0; i--) {
        if(isPadding == 1){
            // đếm phần tử 0 ở cuối
            if (password[i] == 0){
                countZero += 1;
            } else {
                isPadding = 0;
            }
        }
        // đếm số ký tự đặc biệt
        if((password[i] >= 32 && password[i] <= 47) 
            || (password[i] >= 58 && password[i] <= 64) 
            || (password[i] >= 91 && password[i] <= 96) 
            || (password[i] >= 123 && password[i] <= 126)){
            specialCharCount += 1;
        }
    }
    // assert: độ dài >= minLength 
    assert(n - countZero >= minLength && specialCharCount > 0);
}