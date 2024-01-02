CREATE TABLE [Account] (
	[Id] [uniqueidentifier] NOT NULL,
	[Code] [varchar](50) NOT NULL,
	[FullName] [varchar](255) NOT NULL,
	[Email] [varchar](255) NOT NULL,
	[Password] [varchar](255) NOT NULL,
	[LastActivityAt] [datetime],
    CONSTRAINT [PK_Account] PRIMARY KEY ([Id])
);
