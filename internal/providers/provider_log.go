package providers

import "context"

type providerLogKey struct{}

type ProviderLogFunc func(message string)

func WithProviderLog(ctx context.Context, fn ProviderLogFunc) context.Context {
	return context.WithValue(ctx, providerLogKey{}, fn)
}

func EmitProviderLog(ctx context.Context, message string) {
	if ctx == nil {
		return
	}
	fn, ok := ctx.Value(providerLogKey{}).(ProviderLogFunc)
	if !ok || fn == nil {
		return
	}
	fn(message)
}
