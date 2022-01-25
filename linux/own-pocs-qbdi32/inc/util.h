#define PRINT_DEBUG 1
#if PRINT_DEBUG
#define ifprintd(cond, ...) do { if (cond) printf(__VA_ARGS__); } while (0)
#define printd(...)			do { printf(__VA_ARGS__); } while (0)
#else
#define printd(...)			do { } while (0)
#define ifprintd(cond, ...)	do {  } while (0)
#endif