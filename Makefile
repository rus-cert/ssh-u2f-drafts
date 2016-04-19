DOCUMENTS=\
	ssh-u2f

XML_OUTPUT=$(patsubst %,%.xml,$(DOCUMENTS))
HTML_OUTPUT=$(patsubst %,%.html,$(DOCUMENTS))
OUTPUT=$(XML_OUTPUT) $(HTML_OUTPUT)

all: $(OUTPUT)
.PHONY: all

%.xml: %.md
	mmark -xml2 -page $< $@

%.html: %.xml
	xml2rfc --html $<

clean:
	rm -f $(OUTPUT)
