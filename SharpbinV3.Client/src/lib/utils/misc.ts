export function formatBytes(bytes: number, decimals = 2): string {
	if (bytes === 0) return '0 Bytes';

	const unit = 1024;
	const units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

	const exponent = Math.floor(Math.log(bytes) / Math.log(unit));
	const value = bytes / Math.pow(unit, exponent);

	const unitLabel = value === 1 && exponent === 0 ? 'Byte' : units[exponent];
	const formattedValue = Number.isInteger(value) ? value : value.toFixed(decimals);

	return `${formattedValue} ${unitLabel}`;
}

export function formatNumber(num: number): string {
	return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function extractDateFromUUIDv7(uuid?: string): Date | null {
	if (!uuid) return null;
	const hex = uuid.replace(/-/g, '');
	const timestampHex = hex.slice(0, 12);
	return new Date(parseInt(timestampHex, 16));
}

export function isBinaryData(buffer: ArrayBuffer | Uint8Array): boolean {
	const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

	if (bytes.includes(0)) return true;

	try {
		new TextDecoder('utf-8', { fatal: true }).decode(bytes);
		return false;
	} catch {
		return true;
	}
}

export function extractError(resData: unknown): string | null {
	if (!resData || typeof resData !== 'object') return null;

	const data = resData as { errors?: unknown; message?: unknown };

	if (data.errors && typeof data.errors === 'object') {
		return Object.values(data.errors as Record<string, unknown>)
			.flat()
			.filter((v) => typeof v === 'string')
			.join('\n');
	}

	if (typeof data.message === 'string') {
		return data.message;
	}

	return null;
}

export function dateToRelativeString(
	date: Date,
	useSuffix = true,
	full = false,
	nowArg?: Date,
	accuracy = 1
): string {
	const now = nowArg ?? new Date();
	const isFuture = date > now;
	const suffix = useSuffix ? (isFuture ? 'from now' : 'ago') : '';
	const diff = Math.abs(now.getTime() - date.getTime());
	let seconds = Math.floor(diff / 1000);
	const units = [
		{ name: 'year', value: 365 * 24 * 60 * 60 },
		{ name: 'month', value: 30 * 24 * 60 * 60 },
		{ name: 'week', value: 7 * 24 * 60 * 60 },
		{ name: 'day', value: 24 * 60 * 60 },
		{ name: 'hour', value: 60 * 60 },
		{ name: 'minute', value: 60 },
		{ name: 'second', value: 1 }
	];
	if (!full) {
		for (const unit of units) {
			const count = Math.floor(seconds / unit.value);
			if (count > 0) {
				return `${count} ${unit.name}${count > 1 ? 's' : ''} ${suffix}`.trim();
			}
		}
		return `0 seconds ${suffix}`.trim();
	}
	const parts: string[] = [];
	let acc = 0;
	for (const unit of units) {
		if (acc >= accuracy) break;
		const count = Math.floor(seconds / unit.value);
		if (count > 0) {
			parts.push(`${count} ${unit.name}${count > 1 ? 's' : ''}`);
			seconds -= count * unit.value;
			acc++;
		}
	}
	if (parts.length === 0) parts.push('0 seconds');
	return `${parts.join(', ')} ${suffix}`.trim();
}

export function tooltip(node: HTMLElement, text: string) {
	let currentText = text ?? '';
	let tooltipEl: HTMLDivElement | null = null;
	let caretEl: HTMLDivElement | null = null;
	let showTimeout: ReturnType<typeof setTimeout>;
	let hideTimeout: ReturnType<typeof setTimeout>;

	function createTooltip() {
		if (!currentText || currentText.trim() === '') return;
		const el = document.createElement('div');
		el.className =
			'fixed z-50 rounded bg-neutral-800 px-2 py-1 text-sm text-white shadow-lg opacity-0 transition-opacity duration-150';
		el.style.maxWidth = '90%';
		el.style.wordBreak = 'break-word';

		el.addEventListener('mouseover', () => {
			clearTimeout(hideTimeout);
			if (tooltipEl) tooltipEl.style.opacity = '1';
		});
		el.addEventListener('mouseout', mouseOut);

		const lines = currentText.split('\n');
		if (lines.length > 1) {
			el.innerHTML = '';
			lines.forEach((line, index) => {
				const span = document.createElement('span');
				span.textContent = line;
				el.appendChild(span);
				if (index < lines.length - 1) el.appendChild(document.createElement('br'));
			});
		} else {
			el.textContent = currentText;
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

	function updateContent() {
		if (!tooltipEl) return;
		if (!currentText || currentText.trim() === '') {
			tooltipEl.remove();
			tooltipEl = null;
			caretEl = null;
			return;
		}
		const lines = currentText.split('\n');
		tooltipEl.innerHTML = '';
		if (lines.length > 1) {
			lines.forEach((line, index) => {
				const span = document.createElement('span');
				span.textContent = line;
				tooltipEl?.appendChild(span);
				if (index < lines.length - 1) tooltipEl?.appendChild(document.createElement('br'));
			});
		} else {
			tooltipEl.textContent = currentText;
		}
		if (!caretEl) {
			const caret = document.createElement('div');
			caret.style.position = 'absolute';
			caret.style.width = '0';
			caret.style.height = '0';
			caret.style.left = '50%';
			caret.style.transform = 'translateX(-50%)';
			caret.style.pointerEvents = 'none';
			caretEl = caret;
			tooltipEl.appendChild(caretEl);
		} else {
			tooltipEl.appendChild(caretEl);
		}
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
		if (tooltipEl) tooltipEl.style.opacity = '1';
		showTimeout = setTimeout(() => {
			if (!tooltipEl) createTooltip();
			else updateContent();
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
		update(newText: string) {
			currentText = newText ?? '';
			if (!currentText || currentText.trim() === '') {
				if (tooltipEl) {
					tooltipEl.remove();
					tooltipEl = null;
					caretEl = null;
				}
				return;
			}
			if (tooltipEl) {
				updateContent();
				positionTooltip();
			}
		},
		destroy() {
			node.removeEventListener('mouseover', mouseOver);
			node.removeEventListener('mouseout', mouseOut);
			window.removeEventListener('scroll', mouseOut, true);
			window.removeEventListener('resize', mouseOut, true);
			if (tooltipEl) tooltipEl.remove();
		}
	};
}
