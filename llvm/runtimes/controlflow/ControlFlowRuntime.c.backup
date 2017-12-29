#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>

static uint32_t max(uint32_t x, uint32_t y) { return (x > y) ? x : y; }
static uint32_t min(uint32_t x, uint32_t y) { return (x < y) ? x : y; }
static uint32_t clamp(uint32_t x, uint32_t low, uint32_t high) { return max(low, min(x, high)); }

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

// Register functions which should be randomized
void __cf_register(func_t* funcs, uintptr_t* rand_ptrs, uint32_t f_count) {
  ensure_capacity();

  module_t m = { funcs, rand_ptrs, f_count };
  modules[m_count] = m;
  m_count++;

  fprintf(stderr, "[cf-rt] Registered %d functions\n", f_count);
}

static size_t pick_variant(const func_t* f) {
  uint32_t p = rand() % f->probs[f->v_count - 1];
  size_t v = 0;
  while (f->probs[v] <= p) v++;
  return v;
}

static void update(uintptr_t* loc, uintptr_t val) {
  // Only write if necessary to reduce the need for cache flushes
  if (*loc != val) {
    *loc = val;
  }
}

static void randomize_variants() {
  FOR_FUNCTION(f)
    uintptr_t* loc = &modules[_mi].rand_ptrs[_fi];
    uintptr_t  val = f->variants[pick_variant(f)];
    update(loc, val);
  FOR_FUNCTION_END
}

static void* background_thread(void* nanos) {
  struct timespec time;
  time.tv_sec = 0;
  time.tv_nsec = (long) nanos;

  while (1) {
    randomize_variants();
    nanosleep(&time, NULL);
  }
}

static long sleep_time() {
  const char* s = getenv("INDIRECTOR_RUNTIME_SLEEP_NANOS");
  return (s != NULL) ? atol(s) : 100L;
}

static void spawn_thread() {
  long nanos = sleep_time();
  pthread_t thread;
  int ret = pthread_create(&thread, NULL, background_thread, (void*) nanos);
  if (ret) {
    fprintf(stderr, "[cf-rt] Failed to start randomness background thread\n");
    exit(1);
  }
  fprintf(stderr, "[cf-rt] Started randomness background thread, sleep time: %ld ns\n", nanos);
}

typedef struct {
  uint64_t f_count;
  uint64_t total_entry_count;
  uint64_t max_entry_count;
} summary_t;

static summary_t function_summary() {
  summary_t s = {};
  FOR_FUNCTION(f)
    s.f_count += 1;
    s.total_entry_count += f->entry_count;
    s.max_entry_count = max(f->entry_count, s.max_entry_count);
  FOR_FUNCTION_END
  return s;
}

static void collect_functions(func_t** funcs) {
  size_t i = 0;
  FOR_FUNCTION(f)
    funcs[i++] = f;
  FOR_FUNCTION_END
}

static int by_entry_count_desc(const void* a, const void* b) {
  const func_t* const* fa = a;
  const func_t* const* fb = b;
  return -((*fa)->entry_count - (*fb)->entry_count);
}

static void set_probabilities(func_t* f, size_t i, const summary_t* s) {
  assert(f->v_count == 2);
  double ratio = 1.0 * i / s->f_count;
  uint32_t percentile = (uint32_t) ((1 - ratio) * 100);
  uint32_t prob = clamp(percentile, 1, 99); // Probability of unsafe variant: [1%, 99%]

  // Avoid ranges close to 50-50 (worst case for branch predictor)
  if (25 <= prob && prob <= 50) prob = 25;
  if (50 <= prob && prob <= 65) prob = 75;  // TODO(yln): is this expensive?

  f->probs[0] = prob;   // Variant 0 is the one without checks
  f->probs[1] = 100;
}

static void define_policy() {
  summary_t s = function_summary();
  func_t** funcs = malloc(s.f_count * sizeof(func_t*));
  collect_functions(funcs);
  qsort(funcs, s.f_count, sizeof(func_t*), by_entry_count_desc);
  for (size_t i = 0; i < s.f_count; i++) {
    set_probabilities(funcs[i], i, &s);
  }
  free(funcs);
}

__attribute__ ((constructor(0)))
static void initialize_runtime() {
  define_policy();
  srand(time(NULL));    // Initialize RNG // TODO(yln): better randomness?!
  randomize_variants(); // Do one round of randomization manually
  spawn_thread();
}
