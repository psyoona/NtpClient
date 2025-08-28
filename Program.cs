using NtpClient;

try
{
	DateTimeOffset utcTime = new UtcTimeService().GetUtcNowAsync().GetAwaiter().GetResult();

	Console.WriteLine("UTC Time from NTP Server: " + utcTime.ToString("yyyy-MM-dd HH:mm:ss"));
	Console.WriteLine("Local UTC Time: " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
	Console.WriteLine();

	var svc = new UtcTimeService();
	bool changed = await svc.SyncSystemClockAsync(driftThresholdSeconds: 1.0);
	Console.WriteLine(changed ? "시스템 시간을 외부 기준으로 동기화했습니다."
							  : "드리프트가 임계치 미만이라 변경하지 않았습니다.");
}
catch (Exception ex)
{
	Console.WriteLine("Error: " + ex.Message);
}