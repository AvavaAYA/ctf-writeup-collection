## Introduction

A LLVM Pass that can optimize add/sub instructions.

## How to run

opt-12 -load ./mbaPass.so -mba {*.bc/*.ll} -S

## Example

### IR before optimization

```
define dso_local i64 @foo(i64 %0) local_unnamed_addr #0 {
  %2 = sub nsw i64 %0, 2
  %3 = add nsw i64 %2, 68
  %4 = add nsw i64 %0, 6
  %5 = add nsw i64 %4, -204
  %6 = add nsw i64 %5, %3
  ret i64 %6
}
```

### IR after optimization

```
define dso_local i64 @foo(i64 %0) local_unnamed_addr #0 {
  %2 = mul i64 %0, 2
  %3 = add i64 %2, -132
  ret i64 %3
}
```
