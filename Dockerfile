FROM golang:latest
RUN git clone https://github.com/wknapek/credit_cards.git /home/apps/credit_cards
WORKDIR "/home/apps/credit_cards"
RUN go build -o credit
EXPOSE 3001
CMD ["./credit"]