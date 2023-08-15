import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import axios from "axios";

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
  top: 25px;
  left: 25px;
`;

const InputDate = styled.textarea`
  position: relative;
  width: 300px;
  height: 108px;
  left: 22px;
  top: 35px;
  border-radius: 7px;
  border: 1.5px solid #0085ff;
  font-size: 20px;
  padding-left: 15px;
  resize: none;
  ::placeholder {
    color: #7c7c7c;
  }
`;

const SubTitle2 = styled.div`
  position: relative;
  top: 70px;
  left: 25px;
`;

const InputDate2 = styled.textarea`
  position: relative;
  width: 300px;
  height: 108px;
  left: 22px;
  top: 80px;
  border-radius: 7px;
  border: 1.5px solid #0085ff;
  font-size: 20px;
  padding-left: 15px;
  resize: none;

  ::placeholder {
    color: #7c7c7c;
  }
`;

const NewBtn = styled.div`
  position: relative;
  top: 290px;
  left: 22px;
`;

const Date_Write = () => {
  const navigate = useNavigate();
  const [modalOpen, setModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState(""); // 추가
  const [newMemo, setNewMemo] = useState(""); // 추가

  const gotoBack = () => {
    navigate("/Schedule1");
  };
  const onClick = () => {
    if (!newTitle || !newMemo) {
      alert("모든 칸을 입력해주세요.");
      return;
    }

    const code = localStorage.getItem("code");
    const recognizedText = localStorage.getItem("recognizedText");
    const token = localStorage.getItem("token"); // 로컬 스토리지에서 토큰 가져옴
    const headers = { Authorization: `Token ${token}` }; // 헤더에 토큰 추가

    console.log(newTitle);
    console.log(newMemo);
    console.log(recognizedText);
    // 서버에 어차피 저장시켜야 함
    // navigate(`/Date_List`, {
    //   state: { newTitle: newTitle, newMemo: newMemo },
    // });
    // 구분
    try {
      const response = axios.post(
        `http://127.0.0.1:8000/group/${code}/plans/`,
        {
          month: recognizedText,
          title: newTitle,
          memo: newMemo,
        },
        { headers }
      );
      navigate("/Date_List");
    } catch (error) {
      console.error("모임 생성 실패:", error);
    }
  };

  return (
    <Container>
      <Back onClick={gotoBack}>
        <img src={`${process.env.PUBLIC_URL}/images/backbtn.svg`} />
      </Back>
      <Title>
        <img src={`${process.env.PUBLIC_URL}/images/date_plus.svg`} />
      </Title>
      <SubTitle>
        <img src={`${process.env.PUBLIC_URL}/images/subtitle_ask (2).svg`} />
      </SubTitle>
      <InputDate
        value={newTitle}
        onChange={(e) => setNewTitle(e.target.value)}
        placeholder="일정제목을 입력하세요"
      />
      <SubTitle2>
        <img src={`${process.env.PUBLIC_URL}/images/subtitle_write.svg`} />
      </SubTitle2>
      <InputDate2
        value={newMemo}
        onChange={(e) => setNewMemo(e.target.value)}
        placeholder="메모를 입력하세요"
      ></InputDate2>
      <NewBtn onClick={onClick}>
        <img src={`${process.env.PUBLIC_URL}/images/newbtn.svg`} />
      </NewBtn>
    </Container>
  );
};

export default Date_Write;
