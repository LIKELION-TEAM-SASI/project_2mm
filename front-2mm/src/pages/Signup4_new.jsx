import React, { useState, useRef } from "react";
import styled from "styled-components";
import { useNavigate } from "react-router-dom";
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

const Back = styled.button`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
  background: transparent;
  border: none;
`;

const SubTitle = styled.div`
  position: relative;
  top: 25px;
  left: 25px;
`;

const Detail = styled.div`
  position: relative;
  top: 80px;
  left: 25px;
`;

const CopyBox = styled.div`
  position: relative;
  width: 300px;
  height: 35px;
  left: 22px;
  top: 70px;
  border-radius: 7px;
  border: 1.5px solid #0085ff;
  font-size: 16px;
  padding-left: 15px;
  padding-top: 13px;

  ::placeholder {
    color: #7c7c7c;
  }
`;

const CopyBtn = styled.div`
  position: relative;
  top: 100px;
  left: 60px;
`;

const NextBtn = styled.button`
  position: absolute;
  bottom: 50px;
  // left: 32px;
  background: transparent;
  border: none;
  left: 50%; /* 가운데로 정렬하기 위해 왼쪽 위치 조정 */
  transform: translateX(-50%);
`;

const CopyAlert = styled.div`
  position: relative;
  margin-top: 120px;
  left: 100px;
  color: gray; /* 복사됨 텍스트의 색상 */
`;

const Signup4_new = () => {
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);
  const copyBoxRef = useRef(null);
  const inviteCode = localStorage.getItem("code");

  // const handleBackClick = () => {
  //   navigate("/signup3_new"); // Go back to the previous page
  // };

  const handleNextClick = () => {
    navigate("/signup5_new"); // Use navigate to transition to another page
  };

  const handleCopyClick = () => {
    if (copyBoxRef.current) {
      const range = document.createRange();
      range.selectNode(copyBoxRef.current);
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      document.execCommand("copy");
      window.getSelection().removeAllRanges();
      setCopied(true);
      setTimeout(() => {
        setCopied(false);
      }, 2000); // 2초 후에 복사됨 상태 리셋
    }
  };

  return (
    <Container>
      <Back>&nbsp;</Back>
      <Detail>
        <img src={`${process.env.PUBLIC_URL}/images/detail_code.svg`} />
      </Detail>
      <SubTitle>
        <img src={`${process.env.PUBLIC_URL}/images/subtitle_invite2.svg`} />
      </SubTitle>
      <CopyBox ref={copyBoxRef}>{inviteCode}</CopyBox>
      <CopyBtn onClick={handleCopyClick}>
        <img src={`${process.env.PUBLIC_URL}/images/copybtn.svg`} />
      </CopyBtn>
      {/* 복사 상태에 따라 텍스트를 표시하는 요소 */}
      <CopyAlert>{copied ? "주소가 복사되었습니다" : " "} </CopyAlert>
      <NextBtn onClick={handleNextClick}>
        <img src={`${process.env.PUBLIC_URL}/images/nextbtn.svg`} />
      </NextBtn>
    </Container>
  );
};

export default Signup4_new;
