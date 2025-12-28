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
