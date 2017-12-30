#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define FOR_FUNCTION(func)                                  \
for (size_t _mi = 0; _mi < m_count; _mi++) {                \
  for (size_t _fi = 0; _fi < modules[_mi].f_count; _fi++) { \
    func_t* func = &modules[_mi].funcs[_fi];

#define FOR_FUNCTION_END  }}

// Structures for registering control flow variants
typedef struct {
  const uintptr_t* variants;  // Variant pointers
  uint32_t* probs;            // Variant probabilities
  const uint64_t entry_count; // Function entry count (profiling information)
  const uint32_t v_count;     // Number of variants
} func_t;

typedef struct {
  func_t* funcs;        // Function descriptions
  uintptr_t* rand_ptrs; // Randomized pointers
  uint32_t f_count;     // Number of functions
} module_t;

static module_t* modules = NULL;
static uint32_t m_capacity = 0;
static uint32_t m_count = 0;

static void ensure_capacity() {
  if (m_count < m_capacity) return;

  if (m_capacity == 0) m_capacity = 4;
  else m_capacity *= 2;

  modules = (module_t*) realloc(modules, m_capacity * sizeof(module_t));
  assert(modules);
}

void __cf_register(func_t* funcs, uintptr_t* rand_ptrs, uint32_t f_count) {
  ensure_capacity();

  module_t m = { funcs, rand_ptrs, f_count };
  modules[m_count++] = m;
}

void __cf_activate_variant(uintptr_t func, uint32_t variant_no) {
  FOR_FUNCTION(f)
    if (f->variants[0] == func) {
      assert(variant_no < f->v_count);
      modules[_mi].rand_ptrs[_fi] = f->variants[variant_no];
      return;
    }
  FOR_FUNCTION_END
  assert(0); // Function not found/randomized
}

void __cf_activate_variants(uint32_t variant_no) {
  FOR_FUNCTION(f)
    assert(variant_no < f->v_count);
    modules[_mi].rand_ptrs[_fi] = f->variants[variant_no];
  FOR_FUNCTION_END
}

__attribute__ ((constructor(0)))
static void initialize_runtime() {
  __cf_activate_variants(/* variant_no */ 0);
}
