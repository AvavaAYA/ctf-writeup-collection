## `add_student`
 - calloc(0x20)
 - calloc(0x18)

## `give_score`
 - lazy_flag :=> score -= 10

## `give_review`
 - `content_ptr->review_ptr = (char *)calloc(1uLL, v2)`

## free
```c++
if ( student_list[v1]->content_ptr->review_ptr )
	free(student_list[v1]->content_ptr->review_ptr);
free(student_list[v1]->content_ptr);
free(student_list[v1]);
student_list[v1] = 0LL;
--student_count;
```

0x555555559008: 0x0000555555559008      0x0000000400000001
0x555555559018: 0x0000000000000000      0x00007ffff7fc26a0
0x555555559028: 0x0000000000000000      0x00007ffff7fc1980
0x555555559038: 0x0000000100000000      0x0000000000000000
0x555555559048: 0x0000000000000000      0x0000000000000000
0x555555559058: 0x0000000000000000      0x0000000000000003