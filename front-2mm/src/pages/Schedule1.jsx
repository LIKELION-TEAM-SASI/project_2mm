import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { DateText } from "./Schedule1"; // 필요에 따라 import 경로를 조정하세요

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 130px;
`;

const SubTitle = styled.div`
  position: relative;
  left: 20px;
  top: 15px;
  color: #282828;
  font-family: SUIT;
  font-size: 19px;
  font-style: normal;
  font-weight: 700;
  line-height: 141.5%; /* 33.96px */
`;

const VoiceBtn = styled.div`
  position: relative;
  top: 40px;
`;

const InputText = styled.input`
  display: flex;
  justify-content: center;
  align-items: center;
  position: relative;
  height: 50px;
  width: 260px;
  padding: 30px 21px 80px 21px;
  border-radius: 6px;
  border: 1px solid #0057ff;
  top: 70px;
  left: 35px;

  color: #0057ff;
  font-family: SUIT;
  font-size: 50px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;

  text-align: center;
`;

const NextBtn = styled.div`
  position: relative;
  top: 300px;
  left: 22px;
`;

const Schedule1 = () => {
  const navigate = useNavigate();

  const onClickBack = () => {
    navigate("/Date_List");
  };

  // 다음으로 버튼 눌렀을 경우
  const onClickPost = () => {
    if (!recognizedText) {
      alert("모든 칸을 입력해주세요.");
      return;
    }
    // 로컬스토리지에 음성인식값 저장
    localStorage.setItem("recognizedText", recognizedText);
    navigate(`/Date_Write`);
  };

  const [recognizedText, setRecognizedText] = useState("");
  const [isRecognizing, setIsRecognizing] = useState(false);
  const recognitionRef = useRef(null);

  const handleSpeechToText = () => {
    if ("webkitSpeechRecognition" in window) {
      recognitionRef.current = new window.webkitSpeechRecognition();
      recognitionRef.current.lang = "ko-KR";
      recognitionRef.current.interimResults = false;
      recognitionRef.current.maxAlternatives = 1;

      recognitionRef.current.onstart = () => {
        setIsRecognizing(true);
      };

      recognitionRef.current.onspeechend = () => {
        setIsRecognizing(false);
      };

      recognitionRef.current.onresult = (event) => {
        const recognizedText = event.results[0][0].transcript;
        setRecognizedText(recognizedText);
      };

      recognitionRef.current.start();
    } else {
      console.log("음성인식을 지원하지 않는 브라우저입니다.");
    }
  };

  const handleVoiceBtnClick = () => {
    handleSpeechToText();
  };

  return (
    <Container>
      <Back onClick={onClickBack}>
        <img src={`${process.env.PUBLIC_URL}/images/back_btn.svg`} alt="back" />
      </Back>
      <Title>
        <img
          src={`${process.env.PUBLIC_URL}/images/schedule1_title.svg`}
          alt="title"
        />
      </Title>
      <SubTitle>
        버튼을 누르고 <br />몇 월 며칠에 있는 일정인지 말해주세요.
      </SubTitle>
      <VoiceBtn onClick={handleVoiceBtnClick}>
        <img
          src={`${process.env.PUBLIC_URL}/images/post3_btn.svg`}
          alt="post3_btn"
          style={{ width: "100%", height: "100%", objectFit: "cover" }}
        />
      </VoiceBtn>
      <InputText
        value={recognizedText}
        onChange={(event) => setRecognizedText(event.target.value)}
      />
      {/* 다음으로 넘어가는 버튼 */}
      <NextBtn onClick={onClickPost}>
        <img
          src={`${process.env.PUBLIC_URL}/images/schedule1_btn.svg`}
          alt="title"
        />
      </NextBtn>
    </Container>
  );
};

export default Schedule1;
