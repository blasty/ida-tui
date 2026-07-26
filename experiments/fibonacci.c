#include <stdint.h>

/* Iterative Fibonacci. */
uint32_t fib_iter(uint32_t n)
{
    uint32_t a = 0, b = 1;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t t = a + b;
        a = b;
        b = t;
    }
    return a;
}

/* Naive recursive Fibonacci. */
uint32_t fib_rec(uint32_t n)
{
    if (n < 2)
        return n;
    return fib_rec(n - 1) + fib_rec(n - 2);
}

/* Memoized Fibonacci (static table). */
uint32_t fib_memo(uint32_t n)
{
    static uint32_t cache[48];
    if (n < 2)
        return n;
    if (n >= sizeof(cache) / sizeof(cache[0]))
        return fib_iter(n);
    if (cache[n])
        return cache[n];
    return cache[n] = fib_memo(n - 1) + fib_memo(n - 2);
}

volatile uint32_t sink;

int main(void)
{
    for (uint32_t n = 0; n < 20; n++)
        sink = fib_iter(n) + fib_rec(n) + fib_memo(n);
    return 0;
}
