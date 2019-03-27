USE master
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'phx\JIT-MDOLLAR-ADMIN-PROD' and dbname = 'master')
	Begin
CREATE LOGIN [phx\JIT-MDOLLAR-ADMIN-PROD] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [phx\JIT-MDOLLAR-ADMIN-PROD]
GO


--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'phx\JIT-USTNuc-ADMIN-PROD' and dbname = 'master')
	Begin
CREATE LOGIN [phx\JIT-USTNuc-ADMIN-PROD] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [phx\JIT-USTNuc-ADMIN-PROD]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'phx\UST-CORE-TWS' and dbname = 'master')
	Begin
CREATE LOGIN [phx\UST-CORE-TWS] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [phx\UST-CORE-TWS]
GO




--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'Redmond\_wapsro' and dbname = 'master')
	Begin
CREATE LOGIN [Redmond\_wapsro] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [Redmond\_wapsro]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'PHX\_wapsbe' and dbname = 'master')
	Begin
CREATE LOGIN [PHX\_wapsbe] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [PHX\_wapsbe]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'PHX\_wapsfe' and dbname = 'master')
	Begin
CREATE LOGIN [PHX\_wapsfe] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [PHX\_wapsfe]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'PHX\_wapsfe' and dbname = 'master')
	Begin
CREATE LOGIN [PHX\_wapsfe] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [PHX\_wapsfe]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'NT Service\MSSQLServer' and dbname = 'master')
	Begin
CREATE LOGIN [NT Service\MSSQLServer] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [NT Service\MSSQLServer]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'NT Service\SQLServerAgent' and dbname = 'master')
	Begin
CREATE LOGIN [NT Service\SQLServerAgent] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [NT Service\SQLServerAgent]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'NT AUTHORITY\SYSTEM' and dbname = 'master')
	Begin
CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [NT AUTHORITY\SYSTEM]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'NT AUTHORITY\NETWORK SERVICE' and dbname = 'master')
	Begin
CREATE LOGIN [NT AUTHORITY\NETWORK SERVICE] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

--Login Creation
If not Exists (select name from master.dbo.syslogins 
   where name = 'Phx\tws-webstore' and dbname = 'master')
	Begin
CREATE LOGIN [Phx\tws-webstore] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

ALTER SERVER ROLE [sysadmin] ADD MEMBER [Phx\tws-webstore]
GO

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'NT AUTHORITY\NETWORK SERVICE' and dbname = 'master')
	Begin
CREATE LOGIN [NT AUTHORITY\NETWORK SERVICE] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'Phx\tws-fewebidentity' and dbname = 'master')
	Begin
CREATE LOGIN [Phx\tws-fewebidentity] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'PHX\TWS-DatabaseRO' and dbname = 'master')
	Begin
CREATE LOGIN [PHX\TWS-DatabaseRO] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'PHX\_wapscer' and dbname = 'master')
	Begin
CREATE LOGIN [PHX\_wapscer] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'PHX\_TWS-COSMOSSVC' and dbname = 'master')
	Begin
CREATE LOGIN [PHX\_TWS-COSMOSSVC] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end

--Login Creation

If not Exists (select name from master.dbo.syslogins 
   where name = 'Redmond\CertificationReporting' and dbname = 'master')
	Begin
CREATE LOGIN [Redmond\CertificationReporting] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end
Go

--Enable CLR

sp_configure 'show advanced options',1
GO
RECONFIGURE
GO
sp_configure 'clr enabled',1
GO
RECONFIGURE
GO
