// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
	interface Window {
		turnstile?: {
			getResponse: () => string | null;
			render: (container: string | HTMLElement, options?: Record<string, unknown>) => string;
			reset: (widgetId?: string) => void;
			remove: (widgetId?: string) => void;
		};
		turnstileLoaded?: () => void;
	}
	var turnstile:
		| {
				getResponse: () => string | null;
				render: (container: string | HTMLElement, options?: Record<string, unknown>) => string;
				reset: (widgetId?: string) => void;
				remove: (widgetId?: string) => void;
		  }
		| undefined;
	var turnstileLoaded: (() => void) | undefined;
}

export {};
