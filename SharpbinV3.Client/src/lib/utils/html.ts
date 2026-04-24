const htmlEscapeMap: Record<string, string> = {
	'&': '&amp;',
	'<': '&lt;',
	'>': '&gt;',
	'"': '&quot;',
	"'": '&#39;',
	'`': '&#96;'
};

export function escapeHtml(value: string): string {
	return value.replace(/[&<>"'`]/g, (char) => htmlEscapeMap[char]);
}
