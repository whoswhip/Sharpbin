export function parseTotpEnabled(tokenValue: string | null) {
	if (!tokenValue) return false;
	try {
		const payload = JSON.parse(atob(tokenValue.split('.')[1]));
		const flag = payload?.totp;
		if (typeof flag === 'string') return flag.toLowerCase() === 'true';
		return Boolean(flag);
	} catch {
		return false;
	}
}

export function needsAdminTotp(totpEnabled: boolean, currentRoles: number[], nextRoles: number[]) {
	if (!totpEnabled) return false;
	const nextHasAdmin = nextRoles.includes(255);
	const alreadyAdmin = currentRoles.includes(255);
	return nextHasAdmin && !alreadyAdmin;
}
