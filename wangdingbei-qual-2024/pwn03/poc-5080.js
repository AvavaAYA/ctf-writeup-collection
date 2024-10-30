let evil = new RegExp();
evil.exec = () => ({ 0: "1234567", length: 1, index: 0 });
"abc".replace(evil, "$'");
