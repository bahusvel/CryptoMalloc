#ifndef _LOCK_
#define _LOCK_
#include <pthread.h>

#define LOCK_SPIN 0
#define LOCK_MUTEX 1

typedef struct {
	union {
		pthread_mutex_t mutex;
		pthread_spinlock_t spin;
	};
	int lock_type;
} cor_lock;

int lock_init(cor_lock *lock, int lock_type) {
	lock->lock_type = lock_type;
	if (lock_type == LOCK_SPIN) {
		return pthread_spin_init(&lock->spin, PTHREAD_PROCESS_PRIVATE);
	} else {
		return pthread_mutex_init(&lock->mutex, NULL);
	}
}

int lock_lock(cor_lock *lock) {
	if (lock->lock_type == LOCK_SPIN) {
		return pthread_spin_lock(&lock->spin);
	} else {
		return pthread_mutex_lock(&lock->mutex);
	}
}

int lock_unlock(cor_lock *lock) {
	if (lock->lock_type == LOCK_SPIN) {
		return pthread_spin_unlock(&lock->spin);
	} else {
		return pthread_mutex_unlock(&lock->mutex);
	}
}

#endif
