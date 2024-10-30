a = [];
for (var i = 0; i < 100; i++) a.push(i);
a.slice(0, {
  valueOf: function () {
    a.length = 0;
    return 100;
  },
});
