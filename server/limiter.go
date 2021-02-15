/*
 * Copyright (c) 2020-2021 Joe Siltberg
 *
 * You should have received a copy of the MIT license along with this project.
 * If not, see <https://opensource.org/licenses/MIT>.
 */

package server

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// Limiter returns a middleware with token bucket rate limiting applied per entityID
func Limiter(h http.Handler, r rate.Limit, b int) http.Handler {

	limiters := make(map[string]*rate.Limiter)
	var lock sync.Mutex

	getLimiter := func(entity string) *rate.Limiter {
		lock.Lock()
		defer lock.Unlock()

		if limiter, ok := limiters[entity]; ok {
			return limiter
		}
		limiter := rate.NewLimiter(r, b)
		limiters[entity] = limiter
		return limiter
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := getLimiter(EntityIDFromContext(r.Context()))

		if limiter.Wait(r.Context()) != nil {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}
