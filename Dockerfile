FROM golang:latest
RUN git clone https://github.com/wknapek/credit_cards.git /home/apps
WORKDIR "/home/apps/credit_cards"
RUN echo $(pwd)
RUN export GO111MODULE=on
RUN export GOPATH=/home/apps/credit_cards
RUN go build src/main.go
EXPOSE 3001
CMD ["./main.go"]