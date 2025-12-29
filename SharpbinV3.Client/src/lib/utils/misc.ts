export function formatBytes(bytes: number, decimals = 2): string {
	if (bytes === 0) return '0 Bytes';
	const k = 1024;
	const dm = decimals < 0 ? 0 : decimals;
	const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export function extractDateFromUUIDv7(uuid?: string): Date | null {
	if (!uuid) return null;
	const hex = uuid.replace(/-/g, '');
	const timestampHex = hex.slice(0, 12);
	return new Date(parseInt(timestampHex, 16));
}

export function dateToRelativeString(date: Date, useSuffix = true): string {
	const now = new Date();
	const isFuture = date > now;
	const suffix = useSuffix ? (isFuture ? 'from now' : 'ago') : '';
	const diff = Math.abs(now.getTime() - date.getTime());

	const seconds = Math.floor(diff / 1000);
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);
	const days = Math.floor(hours / 24);
	const weeks = Math.floor(days / 7);
	const months = Math.floor(days / 30);
	const years = Math.floor(days / 365);
	if (years > 0) return `${years} year${years > 1 ? 's' : ''} ${suffix}`;
	if (months > 0) return `${months} month${months > 1 ? 's' : ''} ${suffix}`;
	if (weeks > 0) return `${weeks} week${weeks > 1 ? 's' : ''} ${suffix}`;
	if (days > 0) return `${days} day${days > 1 ? 's' : ''} ${suffix}`;
	if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ${suffix}`;
	if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ${suffix}`;
	return `${seconds} second${seconds !== 1 ? 's' : ''} ${suffix}`;
}

export function tooltip(node: HTMLElement, text: string) {
	if (!text || text.trim() === '') return;
	let tooltipEl: HTMLDivElement | null;
	let caretEl: HTMLDivElement | null;
	let showTimeout: ReturnType<typeof setTimeout>;
	let hideTimeout: ReturnType<typeof setTimeout>;

	function createTooltip() {
		const el = document.createElement('div');
		el.textContent = text;
		el.className =
			'fixed z-50 rounded bg-neutral-800 px-2 py-1 text-sm text-white shadow-lg opacity-0 pointer-events-none transition-opacity duration-150';
		el.style.maxWidth = '90%';
		el.style.wordBreak = 'break-word';
		const lines = text.split('\n');
		if (lines.length > 1) {
			el.innerHTML = '';
			lines.forEach((line, index) => {
				const lineEl = document.createElement('div');
				lineEl.textContent = line;
				el.appendChild(lineEl);
				if (index < lines.length - 1) {
					const br = document.createElement('br');
					el.appendChild(br);
				}
			});
		}
		const caret = document.createElement('div');
		caret.style.position = 'absolute';
		caret.style.width = '0';
		caret.style.height = '0';
		caret.style.left = '50%';
		caret.style.transform = 'translateX(-50%)';
		caret.style.pointerEvents = 'none';
		caretEl = caret;
		el.appendChild(caret);
		document.body.appendChild(el);
		tooltipEl = el;
	}

	function positionTooltip() {
		if (!tooltipEl || !caretEl) return;
		const rect = node.getBoundingClientRect();
		const tooltipRect = tooltipEl.getBoundingClientRect();
		let top = rect.top - tooltipRect.height - 8 + window.scrollY;
		let left = rect.left + rect.width / 2 - tooltipRect.width / 2 + window.scrollX;
		let caretOnTop = false;

		if (top < window.scrollY) {
			top = rect.bottom + 8 + window.scrollY;
			caretOnTop = true;
		}
		if (left < 0) left = 8;
		if (left + tooltipRect.width > window.innerWidth)
			left = window.innerWidth - tooltipRect.width - 8;

		tooltipEl.style.top = `${top}px`;
		tooltipEl.style.left = `${left}px`;
		tooltipEl.style.position = 'absolute';

		caretEl.style.top = caretOnTop ? '-7px' : '';
		caretEl.style.bottom = caretOnTop ? '' : '-7px';
		caretEl.style.borderLeft = '7px solid transparent';
		caretEl.style.borderRight = '7px solid transparent';
		if (caretOnTop) {
			caretEl.style.borderBottom = '7px solid #27272a';
			caretEl.style.borderTop = '';
		} else {
			caretEl.style.borderTop = '7px solid #27272a';
			caretEl.style.borderBottom = '';
		}
	}

	function mouseOver() {
		clearTimeout(hideTimeout);
		showTimeout = setTimeout(() => {
			createTooltip();
			positionTooltip();
			requestAnimationFrame(() => {
				if (tooltipEl) tooltipEl.style.opacity = '1';
			});
		}, 200);
	}

	function mouseOut() {
		clearTimeout(showTimeout);
		if (tooltipEl) {
			tooltipEl.style.opacity = '0';
			hideTimeout = setTimeout(() => {
				if (tooltipEl) {
					tooltipEl.remove();
					tooltipEl = null;
					caretEl = null;
				}
			}, 150);
		}
	}

	node.addEventListener('mouseover', mouseOver);
	node.addEventListener('mouseout', mouseOut);
	window.addEventListener('scroll', mouseOut, true);
	window.addEventListener('resize', mouseOut, true);

	return {
		destroy() {
			node.removeEventListener('mouseover', mouseOver);
			node.removeEventListener('mouseout', mouseOut);
			window.removeEventListener('scroll', mouseOut, true);
			window.removeEventListener('resize', mouseOut, true);
			if (tooltipEl) tooltipEl.remove();
		}
	};
}