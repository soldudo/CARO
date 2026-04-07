# Skill: C Memory Safety Remediation Patterns

## 1. Safe Buffer Growth (Integer Overflow Prevention)
When modifying buffer reallocation logic, never use addition to check if a buffer is large enough if user-controlled lengths are involved.
* **Vulnerable Pattern:** `if (len + needed > size) { realloc... }` (Wraps around if `len` is near `SIZE_MAX`).
* **Safe Remediation:** ```c
  /* Ensure size is greater than needed to avoid underflow */
  if (size < needed || size - needed < len) {
      /* Handle overflow / resize buffer safely */
  }

## 2. Pointer Synchronization (Use-After-Free Prevention)
When a buffer is passed to realloc or a custom grow function, the old memory block is invalidated.
* **Remediation Rule:** All struct members or local variables pointing to the old buffer (e.g., cur, base, end) MUST be updated immediately after the reallocation attempt.
* **Error Path Safety:** If the realloc fails, ensure the pointers are not left dangling. Restore them to the old buffer (if it wasn't freed) or set them to NULL.

## 3. Transactional State Preservation
When an operation requires multiple allocations or state changes, do not destroy the old state until the new state is fully realized.
* **Safe Remediation:**
* xmlParserInputPtr old_input = ctxt->input;
xmlParserInputPtr new_input = allocate_new_input();
```c
if (new_input == NULL) {
    /* Rollback safely without corrupting the parser state */
    ctxt->input = old_input;
    return -1; 
}
/* Commit */
free_input(old_input);
ctxt->input = new_input;
```
## 4. Static Syntax & Diff Verification
Since you are generating the patch statically without a compiler, your manual syntax review must be flawless.
* **Mental Compilation:** Audit your C syntax rigorously before finalizing the JSON. Check for missing semicolons, unbalanced brackets, uninitialized variables, and implicit type conversion warnings.
* **Diff Integrity:** The unified diff (`.patch`) format is unforgiving. Ensure your context lines exactly match the surrounding source code (including spaces vs. tabs) and that your line number offsets are mathematically correct. A malformed diff will be rejected by the system.

## Output Template for Final Conclusion
Once your root-cause analysis is complete (Confidence Level >= 90%), your absolute final output must be a single JSON code block. Do not include conversational filler after the JSON block.

The JSON must strictly adhere to this schema to allow for automated extraction