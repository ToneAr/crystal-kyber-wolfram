PATH = (
	FileNames[
		"*.wl",
		FileNameJoin[{ PacletObject["ToneAr/Kyber"]["Location"], "Kernel", "Source" }],
		Infinity
	]
	// Map[FileBaseName]
	// Map["Source`"<>#<>"`"&]
);

Get["ToneAr`Kyber`" <> #]& /@ {
	"Public`",
	"Private`",
	Splice[ PATH ]
};
