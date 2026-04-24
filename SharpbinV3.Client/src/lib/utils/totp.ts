export function parseTotpEnabled(tokenValue: string | null) {
	if (!tokenValue) return false;
	try {
		const payload = JSON.parse(atob(tokenValue.split('.')[1]));
		const flag = payload?.totp_enabled;
		if (typeof flag === 'string') return flag.toLowerCase() === 'true';
		return Boolean(flag);
	} catch {
		return false;
	}
}
